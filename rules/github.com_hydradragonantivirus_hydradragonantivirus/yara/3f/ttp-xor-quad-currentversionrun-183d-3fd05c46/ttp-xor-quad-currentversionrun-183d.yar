rule TTP_XOR_QUAD_CurrentVersionRun_183d {
  strings:
    $key_183d = { 4b 52 [2] 6f 5c [2] 44 70 [2] 6a 52 [2] 7e 49 [2] 71 53 [2] 6f 4e [2] 6d 4f [2] 76 49 [2] 6a 4e [2] 76 61 }

  condition:
    any of them
}