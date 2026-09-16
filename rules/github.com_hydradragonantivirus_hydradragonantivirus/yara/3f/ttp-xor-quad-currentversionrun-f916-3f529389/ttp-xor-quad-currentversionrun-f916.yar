rule TTP_XOR_QUAD_CurrentVersionRun_f916 {
  strings:
    $key_f916 = { aa 79 [2] 8e 77 [2] a5 5b [2] 8b 79 [2] 9f 62 [2] 90 78 [2] 8e 65 [2] 8c 64 [2] 97 62 [2] 8b 65 [2] 97 4a }

  condition:
    any of them
}