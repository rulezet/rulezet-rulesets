rule TTP_XOR_QUAD_CurrentVersionRun_1a3c {
  strings:
    $key_1a3c = { 49 53 [2] 6d 5d [2] 46 71 [2] 68 53 [2] 7c 48 [2] 73 52 [2] 6d 4f [2] 6f 4e [2] 74 48 [2] 68 4f [2] 74 60 }

  condition:
    any of them
}