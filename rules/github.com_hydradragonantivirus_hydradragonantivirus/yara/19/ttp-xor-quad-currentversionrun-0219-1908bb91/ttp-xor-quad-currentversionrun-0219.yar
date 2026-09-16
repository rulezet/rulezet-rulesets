rule TTP_XOR_QUAD_CurrentVersionRun_0219 {
  strings:
    $key_0219 = { 51 76 [2] 75 78 [2] 5e 54 [2] 70 76 [2] 64 6d [2] 6b 77 [2] 75 6a [2] 77 6b [2] 6c 6d [2] 70 6a [2] 6c 45 }

  condition:
    any of them
}