rule TTP_XOR_QUAD_CurrentVersionRun_098c {
  strings:
    $key_098c = { 5a e3 [2] 7e ed [2] 55 c1 [2] 7b e3 [2] 6f f8 [2] 60 e2 [2] 7e ff [2] 7c fe [2] 67 f8 [2] 7b ff [2] 67 d0 }

  condition:
    any of them
}