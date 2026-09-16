rule TTP_XOR_QUAD_CurrentVersionRun_09da {
  strings:
    $key_09da = { 5a b5 [2] 7e bb [2] 55 97 [2] 7b b5 [2] 6f ae [2] 60 b4 [2] 7e a9 [2] 7c a8 [2] 67 ae [2] 7b a9 [2] 67 86 }

  condition:
    any of them
}