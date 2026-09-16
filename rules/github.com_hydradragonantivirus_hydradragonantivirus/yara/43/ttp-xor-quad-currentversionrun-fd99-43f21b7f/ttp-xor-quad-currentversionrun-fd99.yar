rule TTP_XOR_QUAD_CurrentVersionRun_fd99 {
  strings:
    $key_fd99 = { ae f6 [2] 8a f8 [2] a1 d4 [2] 8f f6 [2] 9b ed [2] 94 f7 [2] 8a ea [2] 88 eb [2] 93 ed [2] 8f ea [2] 93 c5 }

  condition:
    any of them
}