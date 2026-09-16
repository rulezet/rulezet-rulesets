rule _media_brian_88D1_7DB91_infected_05_29_18_case109_case109_alfa {
  meta:
    description = "case109 - file alfa.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "4a471333f029f03c8486d3bca677368e8551eb6872cd1d2d07de0a091b8aa30d"

  strings:
    $x1  = "if(!function_exists('bas'.'e'.'64_'.'en'.'code')){function __ZW5jb2Rlcg($data){if(empty($data))return;$b64='ABCDEFGHIJKLMNOPQRST" ascii
    $s2  = "implode($tmp_arr, '');$r = (strlen($data) % 3);return ($r ? substr($enc, 0, ($r - 3)) : $enc).substr('===', ($r || 3));}functio" fullword ascii
    $s3  = "'color' => array(\"shell_border\" => \"#0E304A\",\"header_vars\" => \"#27979B\",\"header_values\" => \"#67ABDF\",\"header_on\" =" ascii
    $s4  = "'post_encryption' => true," fullword ascii
    $s5  = "'login_page' => 'gui'," fullword ascii
    $s6  = "TeVxttE9r7a1gEt1wVk871WVIRmm//DTmndSBtLcLOZt+IHcGGL+qo2KfRnTowzbWn7qjrRCP0ezl/ey91f2HaI90Vs9qv8YO4P9PnjJ7VqvzNSwT/GUcf+TN45BEtfF" ascii
    $s7  = "VeD4W4A6ffZm4EvNGeT9s5rcZb/wEckhfdIVifyDrviH3D57uvphWIR61Z/Qz3x7qu7PGSnjcLt019B5//KQpp5+ucDt0ShVp4xcBouOSpH3/dJxY0mUP2BtcW97F+n/" ascii
    $s8  = "10/mZow2LoxkKnhPrIYm12NEQPuqEBdiI+r1LoQLgc1THQqNHfTpfmLmo3+r39bj4NBSmSi3NU7MwcmFeOu/D2HT8L0a8TtiHmrLzOvS6AE9m0QAh3S96tJbF5Stih8d" ascii
    $s9  = "ZTxWcHj/aGCP37hYM3lu1fAwUHHEvsvT12ubAJe9pYihkY7Xpul3jxb7NBPZhMcKbWIk55Xhn5Y1ocT0+fqGKkczeXABnxH3ifaML0pDKNF62pf7x5rV/i/Fgeti0Bm4" ascii
    $s10 = "uTqL98Iwv8Mvs4uyWiu50oVtLTo1Prli2GskoopfeXArloeROoMjnL/a7r4w+x5zPBug9HfgETI1/J/Q5FStoXQac2e2Mw1c/c4n5COzOQ2/wNZKP8uyCJ5GxJuHlvdS" ascii
    $s11 = "6/T0v3eMo8Sa7ls9jHIoKUvqqPC6bckRXjyRziFGvgIKmw0yt3zAyu4RWcyGmk6056um92ZKdXhLkdehEwjIDVfU7JlRVmXYiAUqEyerxGEvCjsC+vz+ISysTH1XqJ/7" ascii
    $s12 = "\"#27979B\",\"outputs_text\" => \"#67ABDF\",\"outputs_border\" => \"#0E304A\",\"uploader_border\" => \"#0E304A\",\"uploader_back" ascii
    $s13 = "deFdvEmWZ21KzD9C1p/aUBDs59swr6IVqPZlXgKzyuNorYeOuaSH/HEsjurqCRtRuxD25+/dgy5jWyz3mVTdLLLmGxW6svszaauV3jIwkcT1rBSGy3GLBVzriKct8cSz" ascii
    $s14 = "tEDoJrEwGAfs4gRRnH25FVtAK0wU0adb3SvYGTdl+evpnfAhwpk6/STrp4Zjpn94TqG8j4CXA9WllR69KYZtklAAiMpygmXY7FLKAYy16MZzWMgcs1irCoGlKBewMeOi" ascii
    $s15 = "E2kFjHVi/sP0CezleuscrvDk1kgp6lorTJRreXN0bZ1U+4mC07arHFkEgUNER4oCQtfJsR2Ptke2gJvLsIdeOlsVlifKEPvZKvXBTQXmkvAV535IZtScb4sjRX5Gsw+a" ascii
    $s16 = "tFbC03oiWzayvljIV7089k37b/J91yrFwP/vgOpH6smfzGKPpK3bJUjlPGbcQjXdTRKlKXFBFtPcT57Nv0U4UYsAzzYCr7VH334x/9jkuuefcS69Xw2GXZUMwUlTJ97I" ascii
    $s17 = "UWiRcTLa2bN1VdnivzrVylhoNTZKiM89Dtm8sJQo1fHwwVGxQaZcdlO7ieQpbr/NjjkRlok3mk6plSZdzX3ExbfYxZ80nTd/vtKo7keh21iZVnKL0fHEhTiH/ouMB0ED" ascii
    $s18 = "Fs65nYHb89M0HLUQBlXz89IYV+hwSFHW7TDKCqT9weqfY1DNuneUDOvatN+Cc4lDFHN+Bt2GkKMIxnQ3FF/GRLm+KK+lvuuHeADkKfbNwxi4hiamFRJQq0nN0OlIxSWv" ascii
    $s19 = "9wI+/WKBDdE62frRgom4lfVp5muNlIcT+dXF222Ud3H10A3lOGuyBn3wlUurk0s/6OJaFmGeBq11i/Hkk29dlwQ4jbY/E3Rz1alN0lrGXKPfBuamh+46xxUn7qL2IqRu" ascii
    $s20 = "wKPTcGi+ht2JbVEpuMBZM8t5tdidsBfaAEYzqtfDRU5vmDB+O/H2qS+Cp9OGs37ArySOHgOPSeigi6y2DiNuQ3iXXtbp6eye8kyrTNkiVfiTxVtGNGN76q5DltsuY1Xr" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 700KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}