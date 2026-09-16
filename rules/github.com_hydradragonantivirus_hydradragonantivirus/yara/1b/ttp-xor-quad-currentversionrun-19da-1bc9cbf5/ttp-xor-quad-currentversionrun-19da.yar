rule TTP_XOR_QUAD_CurrentVersionRun_19da {
  strings:
    $key_19da = { 4a b5 [2] 6e bb [2] 45 97 [2] 6b b5 [2] 7f ae [2] 70 b4 [2] 6e a9 [2] 6c a8 [2] 77 ae [2] 6b a9 [2] 77 86 }

  condition:
    any of them
}