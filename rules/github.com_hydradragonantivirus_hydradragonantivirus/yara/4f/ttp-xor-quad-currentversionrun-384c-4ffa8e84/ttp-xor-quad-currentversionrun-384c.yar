rule TTP_XOR_QUAD_CurrentVersionRun_384c {
  strings:
    $key_384c = { 6b 23 [2] 4f 2d [2] 64 01 [2] 4a 23 [2] 5e 38 [2] 51 22 [2] 4f 3f [2] 4d 3e [2] 56 38 [2] 4a 3f [2] 56 10 }

  condition:
    any of them
}