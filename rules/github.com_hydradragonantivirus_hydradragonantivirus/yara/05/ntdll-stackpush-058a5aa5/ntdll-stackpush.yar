rule ntdll_stackpush {
  strings:
    $ntdll_stackpush = "hlhntdl" nocase ascii wide

  condition:
    all of them
}