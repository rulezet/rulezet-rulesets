rule emotet_2_index {
  meta:
    description = "PHP - file emotet-2_index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "37dbbe1996e976122e2d87dc8d019e1dc7a9eeb049c59105f819c91c0ce65c26"

  strings:
    $x1  = "class Rst { const PLATFORM_UNKNOWN = 0; const PLATFORM_ANDROID = 1; const PLATFORM_APPLE = 2; const PLATFORM_LINUX = 3; const PL" ascii
    $s2  = "ho $sp0b39f9->execute();" fullword ascii
    $s3  = "itrs.exe'; private $contentType = 'application/octet-stream'; private function spba9f81() { $sp46a5c8 = isset($_SERVER['HTTP_USE" ascii
    $s4  = "n execute() { $sp53dcff = '.' . sha1(basename(dirname(__FILE__))); if (($sp7d2336 = fopen($sp53dcff, 'c+')) !== false) { if (flo" ascii
    $s5  = "sposition: attachment; filename=\"' . $this->contentName . '\"'); header('Content-Transfer-Encoding: binary'); return gzinflate(" ascii
    $s6  = "RSYUfSI08TPDktsSKCR9HMmM0KbXESiJK3jDfsJ95XzrUUNCaccUf09W6FqO87T5aArHft0wbYmSDUmpLDhcExlkUbTKyU9CItI3PzOKsom2Lo2zAmf3Kwsf+HB5fQF5" ascii
    $s7  = "N84+3c//nnWaJEsb+mPjOHPx5V2Vo0vTwx8mxxnet4IGzjIRc294+ufmlleXyTZ8gvMnv1fVf/vcPiKW2y9k+6F5ssDIutGBdKlQoHXZZsoy9JQiV1N8+MtFx5f3vAlK" ascii
    $s8  = "DFzkhrOMelnlMr0l7in0KgwGnHkFL/0/f9XS480uKbTPMp88mWru1AYVm9z5ma1nnCdvm1hn+gaEWZvwLOGFZlrgZz/LdwkO0bmm1F8rNzqNCd/reuC9T6bdUllB48cu" ascii
    $s9  = "TYixZB5F88VfTPlxzVB08uzq7n6/KvyR2KiooUNH1CxasmjJkjd2vbFk2bJlEHXR+Uvi/PRC8V5eYSHr7+7Rw6eHT0Htsrply5Zs2bIFxEPEJUsg/Gk+/EW9m2cHd0/3" ascii
    $s10 = "fm7FdLRGHkN773fqc5PWTlHlM5YsRy+1VJVivtvGkWcgCorPBxKHLItfqRIIGRIOhIAp0CiHreJ7qpgob457bB3EGuGuC1EQdAvKrfcfcTlB5yB3gijXYdIP/6/nDwIG" ascii
    $s11 = "R_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''; $spc3aced = self::PLATFORM_UNKNOWN; if (stripos($sp46a5c8, 'windows') !== false) " ascii
    $s12 = "6CUX488V8dZac+SuDkHNM9FbaQY0HG7q0Whg9xpVR/aktOqjGp94i2A/Z41rb5bvfwjsVwc+fS3EdrcHOHiQrZtfhLOg+XhmvGUAEDHaiuhRVxj5/8pFyxAQv2MmRUqw" ascii
    $s13 = "zLpj8rojzd/5q057hrmoPtgp+HWtO+bybZJqYknd4aUldc1LtV/SwMq6Iye/bfgWRrRDi1Reh8rpA/c+/Gemk74/uuKLBYHf+qt0Hqplp1DLlm3HT+PW7aXvW9Z9QZrC" ascii
    $s14 = "KHuwY5ZrnqyLaCWn0DxSbbUoxU0Q3ysIyVFbviGyP74RamNgKTRKIllOXRl08FXyYaIsN4HXBR/Y6zRi0QGJshZcy/9jpKefos1viSK5viYpRgi0tatck0mqSpysSHJq" ascii
    $s15 = "3yyhz4Byso7/hUi9ID27F6rmSHh/QAkMf76KQP0CCosud4PAKgKlwGJqFE97Ccpy7EbraXIBKCfo270k9MOg5PhVqBOp06BYh3dUS3inQVlcgjtCoJ4GxYP8VIfAuggK" ascii
    $s16 = "uSZwhsvppXDp0cequQazBNiGMHLIQYc5Lfyfm0UIncNmNMrVUPA/m6TA7s8QmqzBzIRbPbwVrjy6YtykPiVMvTeQ7bTcBx5Ps8NR48c5pu+k5jBcrr1a/X9x9u/xTP5x" ascii
    $s17 = "Zf7wW+QsffthE13hO2fT3+PwBBALHdaSBW7ViaHnB3K1kTiYGaEX8s5fB4YL8WcB0nwPQ0GNrjFDxFKSZ7CHZkv2dzB3ATkiVO8DKPgjDfXLq3+TTlzfftxJXEqLogWK" ascii
    $s18 = "B1q1ddiKLjlvMy7xo3pGxFdsnKh+bi3WATw6kIRNUR4MAL7372EkRtMeyEG2dVT1TSI/EuBqJEFr2M+Fgf5DQp6tbDPyG5L1l9bo5RHHYU1SlgnpzPOOgGCMXt79lGFk" ascii
    $s19 = "LoGhChO6E2AnmaoYNDAaZIYJZDTyLXypYW3a9uaoF9yCrYEj1C/OOOMjHi23yC96oF45URPrstUhEARqB3Td2pjWngISEa1mIrQzh3hYjUvDsgCmoCvmLk2ZA+Vek9+H" ascii
    $s20 = "zqLiZ4HYHj8kNwgm4X8qejjC7cLoGLV5cJuMWG3mp8do863k3W+7PW4rG9cPJG0l44cbbx/FWfHh72YJt5mfa3zAREdffn3YVmzoaOApfMB4UE13wRTvm5PM5WoFkKm6" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 800KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}