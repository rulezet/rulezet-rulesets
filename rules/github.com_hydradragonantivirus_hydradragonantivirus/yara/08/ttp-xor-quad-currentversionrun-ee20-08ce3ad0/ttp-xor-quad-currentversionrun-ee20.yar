rule TTP_XOR_QUAD_CurrentVersionRun_ee20 {
  strings:
    $key_ee20 = { bd 4f [2] 99 41 [2] b2 6d [2] 9c 4f [2] 88 54 [2] 87 4e [2] 99 53 [2] 9b 52 [2] 80 54 [2] 9c 53 [2] 80 7c }

  condition:
    any of them
}