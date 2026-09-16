rule TTP_XOR_QUAD_CurrentVersionRun_386a {
  strings:
    $key_386a = { 6b 05 [2] 4f 0b [2] 64 27 [2] 4a 05 [2] 5e 1e [2] 51 04 [2] 4f 19 [2] 4d 18 [2] 56 1e [2] 4a 19 [2] 56 36 }

  condition:
    any of them
}