rule TTP_XOR_QUAD_CurrentVersionRun_211d {
  strings:
    $key_211d = { 72 72 [2] 56 7c [2] 7d 50 [2] 53 72 [2] 47 69 [2] 48 73 [2] 56 6e [2] 54 6f [2] 4f 69 [2] 53 6e [2] 4f 41 }

  condition:
    any of them
}