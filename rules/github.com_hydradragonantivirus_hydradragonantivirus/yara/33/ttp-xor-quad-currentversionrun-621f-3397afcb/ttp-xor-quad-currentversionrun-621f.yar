rule TTP_XOR_QUAD_CurrentVersionRun_621f {
  strings:
    $key_621f = { 31 70 [2] 15 7e [2] 3e 52 [2] 10 70 [2] 04 6b [2] 0b 71 [2] 15 6c [2] 17 6d [2] 0c 6b [2] 10 6c [2] 0c 43 }

  condition:
    any of them
}