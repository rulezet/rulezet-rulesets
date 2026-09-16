rule TTP_XOR_QUAD_CurrentVersionRun_3701 {
  strings:
    $key_3701 = { 64 6e [2] 40 60 [2] 6b 4c [2] 45 6e [2] 51 75 [2] 5e 6f [2] 40 72 [2] 42 73 [2] 59 75 [2] 45 72 [2] 59 5d }

  condition:
    any of them
}