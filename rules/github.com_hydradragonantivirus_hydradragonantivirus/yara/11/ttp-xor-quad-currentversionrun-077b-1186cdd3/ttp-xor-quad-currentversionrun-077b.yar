rule TTP_XOR_QUAD_CurrentVersionRun_077b {
  strings:
    $key_077b = { 54 14 [2] 70 1a [2] 5b 36 [2] 75 14 [2] 61 0f [2] 6e 15 [2] 70 08 [2] 72 09 [2] 69 0f [2] 75 08 [2] 69 27 }

  condition:
    any of them
}