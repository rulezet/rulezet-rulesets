rule TTP_XOR_QUAD_CurrentVersionRun_3851 {
  strings:
    $key_3851 = { 6b 3e [2] 4f 30 [2] 64 1c [2] 4a 3e [2] 5e 25 [2] 51 3f [2] 4f 22 [2] 4d 23 [2] 56 25 [2] 4a 22 [2] 56 0d }

  condition:
    any of them
}