rule TTP_XOR_QUAD_CurrentVersionRun_372f {
  strings:
    $key_372f = { 64 40 [2] 40 4e [2] 6b 62 [2] 45 40 [2] 51 5b [2] 5e 41 [2] 40 5c [2] 42 5d [2] 59 5b [2] 45 5c [2] 59 73 }

  condition:
    any of them
}