rule TTP_XOR_QUAD_CurrentVersionRun_c502 {
  strings:
    $key_c502 = { 96 6d [2] b2 63 [2] 99 4f [2] b7 6d [2] a3 76 [2] ac 6c [2] b2 71 [2] b0 70 [2] ab 76 [2] b7 71 [2] ab 5e }

  condition:
    any of them
}