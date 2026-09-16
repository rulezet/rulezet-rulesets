rule TTP_XOR_QUAD_CurrentVersionRun_763f {
  strings:
    $key_763f = { 25 50 [2] 01 5e [2] 2a 72 [2] 04 50 [2] 10 4b [2] 1f 51 [2] 01 4c [2] 03 4d [2] 18 4b [2] 04 4c [2] 18 63 }

  condition:
    any of them
}