rule FinSpy_TippyPad: finspyTP {
  meta:
    description = "Detect FinFisher FinSpy 'TippyPad' variant."
    date        = "2020/08/05"
    author      = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"

  strings:
    $pad_1 = "0123456789abcdef"
    $pad_2 = "fedcba9876543210"

  condition:
    uint16(0) == 0x6564 and
    #pad_1 > 50 and
    #pad_2 > 50
}