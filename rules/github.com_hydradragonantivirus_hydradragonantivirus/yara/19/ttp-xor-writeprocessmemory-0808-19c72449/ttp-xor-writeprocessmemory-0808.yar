rule TTP_XOR_WriteProcessMemory_0808 {
  strings:
    $key_0808 = { 5f 7a [2] 6d 58 [2] 6b 6d [2] 45 6d [2] 7a 71 }

  condition:
    any of them
}