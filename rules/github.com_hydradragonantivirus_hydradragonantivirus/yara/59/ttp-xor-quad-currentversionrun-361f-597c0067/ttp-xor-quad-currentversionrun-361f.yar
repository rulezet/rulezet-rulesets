rule TTP_XOR_QUAD_CurrentVersionRun_361f {
  strings:
    $key_361f = { 65 70 [2] 41 7e [2] 6a 52 [2] 44 70 [2] 50 6b [2] 5f 71 [2] 41 6c [2] 43 6d [2] 58 6b [2] 44 6c [2] 58 43 }

  condition:
    any of them
}