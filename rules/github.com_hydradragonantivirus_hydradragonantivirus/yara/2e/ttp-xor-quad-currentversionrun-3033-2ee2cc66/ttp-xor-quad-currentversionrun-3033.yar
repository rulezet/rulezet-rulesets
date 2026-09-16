rule TTP_XOR_QUAD_CurrentVersionRun_3033 {
  strings:
    $key_3033 = { 63 5c [2] 47 52 [2] 6c 7e [2] 42 5c [2] 56 47 [2] 59 5d [2] 47 40 [2] 45 41 [2] 5e 47 [2] 42 40 [2] 5e 6f }

  condition:
    any of them
}