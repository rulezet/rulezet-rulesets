rule TTP_XOR_QUAD_CurrentVersionRun_c54e {
  strings:
    $key_c54e = { 96 21 [2] b2 2f [2] 99 03 [2] b7 21 [2] a3 3a [2] ac 20 [2] b2 3d [2] b0 3c [2] ab 3a [2] b7 3d [2] ab 12 }

  condition:
    any of them
}