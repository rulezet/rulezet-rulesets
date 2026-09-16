rule TTP_XOR_QUAD_CurrentVersionRun_0f1c {
  strings:
    $key_0f1c = { 5c 73 [2] 78 7d [2] 53 51 [2] 7d 73 [2] 69 68 [2] 66 72 [2] 78 6f [2] 7a 6e [2] 61 68 [2] 7d 6f [2] 61 40 }

  condition:
    any of them
}