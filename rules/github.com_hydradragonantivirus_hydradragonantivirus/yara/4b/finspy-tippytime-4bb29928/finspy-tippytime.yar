rule FinSpy_TippyTime: finspyTT {
  meta:
    description = "Detect FinFisher FinSpy 'TippyTime' variant."
    date        = "2020/08/05"
    author      = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"

  strings:
    $config_1  = { 90 5b fe 00 }
    $config_2  = { 70 37 80 00 }
    $config_3  = { 40 38 80 00 }
    $config_4  = { a0 33 84 }
    $config_5  = { 90 79 84 00 }
    $timestamp = { 95 E9 D1 5B }

  condition:
    uint16(0) == 0x6564 and
    $timestamp and
    $config_1 and
    $config_2 and
    $config_3 and
    $config_4 and
    $config_5
}