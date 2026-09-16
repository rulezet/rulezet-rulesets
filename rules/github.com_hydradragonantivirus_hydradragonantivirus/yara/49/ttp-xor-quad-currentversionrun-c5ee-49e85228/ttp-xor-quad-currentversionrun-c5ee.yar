rule TTP_XOR_QUAD_CurrentVersionRun_c5ee {
  strings:
    $key_c5ee = { 96 81 [2] b2 8f [2] 99 a3 [2] b7 81 [2] a3 9a [2] ac 80 [2] b2 9d [2] b0 9c [2] ab 9a [2] b7 9d [2] ab b2 }

  condition:
    any of them
}