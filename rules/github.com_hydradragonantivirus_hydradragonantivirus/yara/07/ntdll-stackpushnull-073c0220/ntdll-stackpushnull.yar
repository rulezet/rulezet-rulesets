rule ntdll_stackpushnull {
  strings:
    $ntdll_stackpushnull = "hl\x00hntdl" nocase ascii wide

  condition:
    all of them
}