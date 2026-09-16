rule Multi_Hacktool_LinPEAS_ng_1eb10406 {
    meta:
        author = "Elastic Security"
        id = "1eb10406-aed8-4411-9b6a-5e9cada72c29"
        fingerprint = "d48658714fdab4127535a91ee883e9d0443ed46b6d4c9ff88543cb9f5e940462"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the cloud module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cloud_0 = "/devstorage.read_only|/logging.write" base64
        $cloud_1 = "/monitoring|/servicecontrol|/service.management.readonly" base64
        $cloud_2 = "grep -q metadata.google.internal /etc/hosts" base64
        $cloud_3 = "Google Cloud Platform?" base64
        $cloud_4 = "AWS ECS?" base64
        $cloud_5 = "Project-ID:" base64
        $cloud_6 = "OSLogin users:" base64
        $cloud_7 = "Instance Image:" base64
        $cloud_8 = "X-aws-ec2-metadata-token:" base64
        $cloud_9 = "AWS Lambda Enumeration" base64
    condition:
        5 of them
}