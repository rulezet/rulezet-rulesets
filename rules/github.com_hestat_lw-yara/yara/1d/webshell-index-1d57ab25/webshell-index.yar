rule webshell_index {
   meta:
      description = "PHP - file webshell_index.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2019-10-11"
      hash1 = "b6a4dc08202aa6653ef33e40fc29674a6f4bd6c75c7dcf13a3b27f06ccfdf1a8"
   strings:
      $x1 = "$OOO__00O0_=\"kvlqst2onx-zpaf7edg5jcu6mr0b983iy_4h1w\";$O0O_0OO0__=$OOO__00O0_{4}.$OOO__00O0_{5}.$OOO__00O0_{25}.$OOO__00O0_{16}" ascii
      $s2 = "x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"])?80:$OO00__O0O_[\"\\x4f\\x5f\\x4f\\x4f\\x5f\\x5f\\x30\\x30\\x30\\x4f\"];}$OOO00__" ascii
      $s3 = "_0=$OOO__00O0_{17}.$OOO__00O0_{13}.$OOO__00O0_{5}.$OOO__00O0_{16};header('Content-Type:text/html;charset=utf-8');${\"\\x47\\x4c" ascii
      $s4 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O0O0_O0_O_);$O_O_00O0O_=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s5 = "0\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f\\x4f\"](\"/%host%/si\",$OO__O000_O,$O_O_00O0O_);$OO_0_O0O_0=${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s6 = "__0.\\'|\\'.$OO00_O_O0_);$O0O0O_0_O_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x30\\x4f\\x30\\x30\\x5f\\x5f\\x5f\\x4f" ascii
      $s7 = "}[\"\\x4f\\x5f\\x4f\\x4f\\x30\\x5f\\x5f\\x30\\x4f\\x30\"]($OO___O000O,CURLOPT_USERAGENT,\\'WHR\\');${\"\\x47\\x4c\\x4f\\x42\\x41" ascii
      $s8 = "f\"](\\'c0xOThTi0osdLtPS1wIA\\');unset($OOO00__O0_);$OO__O_0O00=\"GET $O0O0__OO_0 HTTP/$O__O00O0_O\\\\r\\\\n\".${\"\\x47\\x4c\\x" ascii
      $s9 = "O_00.\\'/\\'.$OOO_O__000)){$OOOO00_0__Array[] =$OOO_O__000;}}$OO_O__000O=\\'temp\\';$OOOO00_0__Array[] =$OO_O__000O;return $OOOO" ascii
      $s10 = "O_0O00_O_).\\'.txt\\';$O0O__0OO0_=${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x4f\\x5f\\x4f\\x5f\\x4f\\x4f\\x30\\x30\\x5f\\x3" ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 100KB and
         ( 1 of ($x*) and all of them )
      ) or ( all of them )
}