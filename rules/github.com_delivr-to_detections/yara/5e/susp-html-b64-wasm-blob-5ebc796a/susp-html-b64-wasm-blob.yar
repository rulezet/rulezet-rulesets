rule SUSP_HTML_B64_WASM_Blob {
   meta:
      description = "Presence of WASM blob based on raw or encoded magic bytes"
      author = "delivr.to"
      date = "2024-02-28"
      score = 70
   strings:
      $m = { 00 61 73 6D }
      $m64 = "AGFzbQ" 
      $m64x2 = "kFHRnpiUU"
   condition:
      any of them
}