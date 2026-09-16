rule ntdll_decimal {
  strings:
    $ntdll_decimal = "110 116 100 108 108" nocase ascii wide

  condition:
    all of them
}