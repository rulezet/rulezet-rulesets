rule ntdll_fallchill {
  strings:
    $ntdll_fallchill = "mgwoo" nocase ascii wide

  condition:
    all of them
}