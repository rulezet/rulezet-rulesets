rule Multi_Hacktool_LinPEAS_ng_d233c491 {
    meta:
        author = "Elastic Security"
        id = "d233c491-d506-49d4-958d-a13ef77fcc71"
        fingerprint = "b6a805f34fb1b7847c1d1180f8c43742aadfa4f9667ad590d3266b69cfde7419"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the cloud module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cloud_0 = "/devstorage.read_only|/logging.write"
        $cloud_1 = "/monitoring|/servicecontrol|/service.management.readonly"
        $cloud_2 = "grep -q metadata.google.internal /etc/hosts"
        $cloud_3 = "Google Cloud Platform?"
        $cloud_4 = "AWS ECS?"
        $cloud_5 = "Project-ID:"
        $cloud_6 = "OSLogin users:"
        $cloud_7 = "Instance Image:"
        $cloud_8 = "X-aws-ec2-metadata-token:"
        $cloud_9 = "AWS Lambda Enumeration"
    condition:
        5 of them
}