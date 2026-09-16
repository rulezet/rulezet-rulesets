rule DELIVRTO_SUSP_HTML_WASM_Smuggling {
  meta:
    description = "Presence of Base64 JavaScript blob loading WASM"
    author      = "delivr.to"
    id          = "fc83bb4f-ba8a-52d2-b9ce-632da5341f77"
    date        = "2024-02-28"
    modified    = "2024-05-24"
    reference   = "https://github.com/delivr-to/detections"
    source_url  = "https://github.com/delivr-to/detections/blob/d2dcf7e9566e39655994aa0c5f8fb7a94cae2984/yara-rules/html_wasm.yar#L1-L13"
    license_url = "N/A"
    logic_hash  = "4bca88862c28db947c04c40e40fdecc682223d1eb90c98350fbd6c5d8c6c4636"
    score       = 70
    quality     = 80
    tags        = ""

  strings:
    $wasm = "WebAssembly.Module" base64
    $int  = "WebAssembly.Instance" base64
    $inst = "WebAssembly.instantiate" base64

  condition:
    all of them
}