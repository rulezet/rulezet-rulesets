rule TTP_XOR_QUAD_CurrentVersionRun_760f {
  strings:
    $key_760f = { 25 60 [2] 01 6e [2] 2a 42 [2] 04 60 [2] 10 7b [2] 1f 61 [2] 01 7c [2] 03 7d [2] 18 7b [2] 04 7c [2] 18 53 }

  condition:
    any of them
}