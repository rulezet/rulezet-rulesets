rule TTP_XOR_QUAD_CurrentVersionRun_eea3 {
  strings:
    $key_eea3 = { bd cc [2] 99 c2 [2] b2 ee [2] 9c cc [2] 88 d7 [2] 87 cd [2] 99 d0 [2] 9b d1 [2] 80 d7 [2] 9c d0 [2] 80 ff }

  condition:
    any of them
}