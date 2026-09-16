rule TTP_XOR_QUAD_CurrentVersionRun_ee22 {
  strings:
    $key_ee22 = { bd 4d [2] 99 43 [2] b2 6f [2] 9c 4d [2] 88 56 [2] 87 4c [2] 99 51 [2] 9b 50 [2] 80 56 [2] 9c 51 [2] 80 7e }

  condition:
    any of them
}