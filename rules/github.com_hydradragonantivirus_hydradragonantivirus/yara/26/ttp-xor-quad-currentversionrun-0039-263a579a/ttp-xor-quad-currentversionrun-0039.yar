rule TTP_XOR_QUAD_CurrentVersionRun_0039 {
  strings:
    $key_0039 = { 53 56 [2] 77 58 [2] 5c 74 [2] 72 56 [2] 66 4d [2] 69 57 [2] 77 4a [2] 75 4b [2] 6e 4d [2] 72 4a [2] 6e 65 }

  condition:
    any of them
}