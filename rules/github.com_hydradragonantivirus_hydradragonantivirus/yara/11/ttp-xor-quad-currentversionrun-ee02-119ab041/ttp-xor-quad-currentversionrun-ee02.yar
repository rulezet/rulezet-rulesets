rule TTP_XOR_QUAD_CurrentVersionRun_ee02 {
  strings:
    $key_ee02 = { bd 6d [2] 99 63 [2] b2 4f [2] 9c 6d [2] 88 76 [2] 87 6c [2] 99 71 [2] 9b 70 [2] 80 76 [2] 9c 71 [2] 80 5e }

  condition:
    any of them
}