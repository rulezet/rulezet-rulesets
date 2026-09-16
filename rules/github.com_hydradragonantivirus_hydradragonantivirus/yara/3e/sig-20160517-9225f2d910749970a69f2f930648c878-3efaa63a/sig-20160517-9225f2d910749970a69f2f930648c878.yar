rule sig_20160517_9225f2d910749970a69f2f930648c878 {
  meta:
    description = "datamaliciousorder - file 20160517_9225f2d910749970a69f2f930648c878.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29ad1b6e2af99bb22b49eff6c34db4df3490f9ff60eb38436e35406766afe11c"

  strings:
    $s1 = "var cnmqee='vrphfqakrjlnrbjwwx ykrutplltssjccb43mkjrks4bakvqsac4x4mjznsuwbqfaj4tnpcr2xfaju=qvyhq\\'ajxsgtdtgnmcrydj4nklrgsiw32nl" ascii
    $s2 = " deyvntq3qx=r4+\"v\"+\"al\";   WScript.lister=5;   deyvntq3qx=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}