rule TTP_XOR_QUAD_CurrentVersionRun_e431 {
  strings:
    $key_e431 = { b7 5e [2] 93 50 [2] b8 7c [2] 96 5e [2] 82 45 [2] 8d 5f [2] 93 42 [2] 91 43 [2] 8a 45 [2] 96 42 [2] 8a 6d }

  condition:
    any of them
}