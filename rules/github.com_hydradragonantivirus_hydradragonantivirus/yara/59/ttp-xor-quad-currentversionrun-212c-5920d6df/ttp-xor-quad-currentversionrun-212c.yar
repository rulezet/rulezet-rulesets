rule TTP_XOR_QUAD_CurrentVersionRun_212c {
  strings:
    $key_212c = { 72 43 [2] 56 4d [2] 7d 61 [2] 53 43 [2] 47 58 [2] 48 42 [2] 56 5f [2] 54 5e [2] 4f 58 [2] 53 5f [2] 4f 70 }

  condition:
    any of them
}