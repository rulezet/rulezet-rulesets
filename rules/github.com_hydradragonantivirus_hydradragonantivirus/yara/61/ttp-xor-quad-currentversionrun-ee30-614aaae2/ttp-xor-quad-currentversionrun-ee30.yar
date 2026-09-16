rule TTP_XOR_QUAD_CurrentVersionRun_ee30 {
  strings:
    $key_ee30 = { bd 5f [2] 99 51 [2] b2 7d [2] 9c 5f [2] 88 44 [2] 87 5e [2] 99 43 [2] 9b 42 [2] 80 44 [2] 9c 43 [2] 80 6c }

  condition:
    any of them
}