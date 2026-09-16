rule TTP_XOR_QUAD_CurrentVersionRun_3023 {
  strings:
    $key_3023 = { 63 4c [2] 47 42 [2] 6c 6e [2] 42 4c [2] 56 57 [2] 59 4d [2] 47 50 [2] 45 51 [2] 5e 57 [2] 42 50 [2] 5e 7f }

  condition:
    any of them
}