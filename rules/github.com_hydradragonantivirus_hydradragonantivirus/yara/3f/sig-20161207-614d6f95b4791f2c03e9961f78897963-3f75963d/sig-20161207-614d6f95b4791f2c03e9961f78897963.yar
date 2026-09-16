rule sig_20161207_614d6f95b4791f2c03e9961f78897963 {
  meta:
    description = "datamaliciousorder - file 20161207_614d6f95b4791f2c03e9961f78897963.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e3c110b8f8ac3788cbb36976570f84704888e365d96147886886486d0b874b9"

  strings:
    $s1 = "new Date();vDr8[\"setUTCFullYear\"](\"2003\");if (vDr8.getUTCFullYear().toString(10) == \"2003\") {var vGh1 = vUm2.split(\"####" ascii
    $s2 = "var vDy1 = new Function(\"vUm2\", '{return vUm2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXGw7 = new Function(\"vUm2" ascii
    $s3 = "rn vGh1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vDy1 = new Function(\"vUm2\", '{return vUm2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXGw7 = new Function(\"vUm2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}