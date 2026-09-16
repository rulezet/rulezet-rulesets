rule TTP_XOR_QUAD_CurrentVersionRun_9898 {
  strings:
    $key_9898 = { cb f7 [2] ef f9 [2] c4 d5 [2] ea f7 [2] fe ec [2] f1 f6 [2] ef eb [2] ed ea [2] f6 ec [2] ea eb [2] f6 c4 }

  condition:
    any of them
}