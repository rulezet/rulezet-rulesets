rule TTP_XOR_QUAD_CurrentVersionRun_3051 {
  strings:
    $key_3051 = { 63 3e [2] 47 30 [2] 6c 1c [2] 42 3e [2] 56 25 [2] 59 3f [2] 47 22 [2] 45 23 [2] 5e 25 [2] 42 22 [2] 5e 0d }

  condition:
    any of them
}