rule TTP_XOR_QUAD_CurrentVersionRun_077a {
  strings:
    $key_077a = { 54 15 [2] 70 1b [2] 5b 37 [2] 75 15 [2] 61 0e [2] 6e 14 [2] 70 09 [2] 72 08 [2] 69 0e [2] 75 09 [2] 69 26 }

  condition:
    any of them
}