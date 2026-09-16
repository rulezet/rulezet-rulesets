rule sig_20161208_695309289329ad36a25f640cb377142e {
  meta:
    description = "datamaliciousorder - file 20161208_695309289329ad36a25f640cb377142e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3d5bd8e9871adc054060700fcf5936c7d690570cef014da35408355d4b5de27"

  strings:
    $s1 = "var vLi2 = new Function(\"vKIs8\", '{return vKIs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKd5 = new Function(\"vKIs" ascii
    $s2 = "= new Date();vPq9[\"setUTC\"+\"FullYear\"](\"2003\");if (vPq9.getUTCFullYear().toString(10) == \"2003\") {var vNZh0 = vKIs8.spli" ascii
    $s3 = "); return vNZh0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vLi2 = new Function(\"vKIs8\", '{return vKIs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKd5 = new Function(\"vKIs" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}